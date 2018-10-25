import datetime
import struct


def as_signed_le(bs):
    if len(bs) <= 0 or len(bs) > 8:
        raise ValueError()

    signed_format = {1: 'b', 2: 'h', 4: 'l', 8: 'q'}

    fill = b'\xFF' if ((bs[-1] & 0x80) >> 7) == 1 else b'\x00'

    while len(bs) not in signed_format:
        bs = bs + fill

    return struct.unpack('<' + signed_format[len(bs)], bs)[0]


def parse_boot_sector(bytes):
    """
    Returns a dictionary of the contents of the NTFS boot sector.
    Key names based on the 'Partition Boot Sector' section of the NTFS Wikipedia page.


    :param bytes: 512-bytes of the beginning of a NTFS partition
    :return: Dictionary containing the contents extracted from the bytes
    """
    boot_sec_dir = {}
    boot_sec_dir['JMP Instruction'] = bytes[:3]  # unused
    boot_sec_dir['OEM ID'] = bytes[3:11]  # unused
    boot_sec_dir['Bytes per sector'] = as_signed_le(bytes[11:13])
    boot_sec_dir['Sectors per cluster'] = as_signed_le(bytes[13:14])
    boot_sec_dir['Reserved sectors'] = as_signed_le(bytes[14:16])  # should always be 0
    boot_sec_dir['Media descriptor'] = bytes[21:22]
    boot_sec_dir['Sectors per track'] = as_signed_le(bytes[24:26])
    boot_sec_dir['Number of heads'] = as_signed_le(bytes[26:28])
    boot_sec_dir['Hidden sectors'] = as_signed_le(bytes[28:32])
    boot_sec_dir['Total sectors'] = as_signed_le(bytes[40:48])
    boot_sec_dir['$MFT cluster number'] = as_signed_le(bytes[48:56])
    boot_sec_dir['$MFTMirr cluster number'] = as_signed_le(bytes[56:64])

    # Im actually storing these values as the number of bytes, not clusters
    bytes_per_file_record = as_signed_le(bytes[64:65])
    bytes_per_index = as_signed_le(bytes[68:69])

    if bytes_per_file_record < 0:
        bytes_per_file_record = pow(2, abs(bytes_per_file_record))
    else:
        bytes_per_file_record *= boot_sec_dir['Sectors per cluster'] * boot_sec_dir['Bytes per sector']
    if bytes_per_index < 0:
        bytes_per_index = pow(2, abs(bytes_per_index))
    else:
        bytes_per_index *= boot_sec_dir['Sectors per cluster'] * boot_sec_dir['Bytes per sector']

    boot_sec_dir['Bytes Per File Record Segment'] = bytes_per_file_record
    boot_sec_dir['Bytes Per Index Buffer'] = bytes_per_index

    boot_sec_dir['Volume serial number'] = bytes[72:80]
    boot_sec_dir['Checksum'] = bytes[80:84]  # unused
    boot_sec_dir['Bootstrap code'] = bytes[84:510]
    boot_sec_dir['End-of-sector Marker'] = bytes[510:512]
    return boot_sec_dir


def istat_ntfs(f, address, sector_size=512, offset=0):
    bytes = f.read()
    result = []
    boot_sector = parse_boot_sector(bytes[0:sector_size])
    cluster_size = boot_sector['Bytes per sector'] * boot_sector['Sectors per cluster']
    MFT_start = cluster_size * boot_sector['$MFT cluster number']
    MFT_start = MFT_start + (boot_sector['Bytes Per File Record Segment'] * address)
    MFT_header = bytes[MFT_start:MFT_start + 56]

    # MFT header values
    MFT_header_entry = as_signed_le(MFT_header[44:48])
    MFT_header_seq = as_signed_le(MFT_header[16:18])
    MFT_header_log_seq = as_signed_le(MFT_header[8:16])
    MFT_header_attr_offset = as_signed_le(MFT_header[20:22])

    result.append('MFT Entry Header Values:')
    result.append('Entry: ' + str(MFT_header_entry) + '        ' + 'Sequence: ' + str(MFT_header_seq))
    result.append('$LogFile Sequence Number: ' + str(MFT_header_log_seq))
    result.append('Allocated File')
    result.append('Links: 1')
    result.append('\n')

    # Standard Info values
    attr_start = MFT_header_attr_offset + MFT_start
    std_info_header = bytes[attr_start:attr_start+14]
    attr_length = as_signed_le(std_info_header[4:8])
    attr_types = {0x10: '$STANDARD_INFORMATION', 0x30: '$FILE_NAME', 0x80: '$DATA'}
    std_info_type = attr_types.get(as_signed_le(std_info_header[:4]))
    if as_signed_le(std_info_header[12:]) == 0:
        std_info_is_resident = True
    else:
        std_info_is_resident = False

    if std_info_is_resident:
        attr_continued = bytes[attr_start+14:attr_start+22]  # resident header continuation is 8 bytes
    else:
        attr_continued = bytes[attr_start+14:attr_start+64]  # non-resident header continuation is 50 bytes

    std_info_type_id = as_signed_le(std_info_header[:4])
    std_info_attr_id = as_signed_le(attr_continued[:2])
    std_info_content_size = as_signed_le(attr_continued[2:6])
    attr_content_offset = as_signed_le(attr_continued[6:8])

    flags = {0x01: 'Read Only', 0x02: 'Hidden', 0x04: 'System', 0x20: 'Archive', 0x40: 'Device', 0x80: 'Normal',
             0x03: 'Read Only, Hidden', 0x05: 'Read Only, System', 0x06: 'Hidden, System'}

    attr_content = bytes[attr_start + attr_content_offset: attr_start + attr_content_offset + std_info_content_size]
    attr_created_time = into_localtime_string(as_signed_le(attr_content[:8]))
    attr_modified_time = into_localtime_string(as_signed_le(attr_content[8:16]))
    attr_mft_modified_time = into_localtime_string(as_signed_le(attr_content[16:24]))
    attr_accessed = into_localtime_string(as_signed_le(attr_content[24:32]))
    attr_owner_id = as_signed_le(attr_content[44:48])
    attr_flags = flags.get(as_signed_le(attr_content[32:36]))

    result.append('$STANDARD_INFORMATION Attribute Values:')
    result.append('Flags: ' + attr_flags)
    result.append('Owner ID: ' + str(attr_owner_id))
    result.append('Created:\t' + attr_created_time)
    result.append('File Modified:\t' + attr_modified_time)
    result.append('MFT Modified:\t' + attr_mft_modified_time)
    result.append('Accessed:\t' + attr_accessed)
    result.append('\n')

    # File name values
    attr_start += attr_length
    attr_header = bytes[attr_start:attr_start+14]
    file_attr_type_id = as_signed_le(attr_header[:4])
    file_attr_type = attr_types.get(file_attr_type_id)
    file_attr_length = as_signed_le(attr_header[4:8])
    if as_signed_le(attr_header[12:]) == 0:
        file_attr_is_resident = True
    else:
        file_attr_is_resident = False

    if file_attr_is_resident:
        attr_continued = bytes[attr_start+14:attr_start+22]  # resident header continuation is 8 bytes
    else:
        attr_continued = bytes[attr_start+14:attr_start+64]  # non-resident header continuation is 50 bytes

    file_attr_id = as_signed_le(attr_continued[:2])
    file_content_size = as_signed_le(attr_continued[2:6])
    attr_content_offset = as_signed_le(attr_continued[6:8])

    attr_content = bytes[attr_start + attr_content_offset: attr_start + attr_content_offset + file_content_size]
    file_attr_parent_dir_num = as_signed_le(attr_content[:6])
    file_attr_parent_dir_seq = as_signed_le(attr_content[6:8])
    file_attr_creation = into_localtime_string(as_signed_le(attr_content[8:16]))
    file_attr_modified = into_localtime_string(as_signed_le(attr_content[16:24]))
    file_attr_mft_modified = into_localtime_string(as_signed_le(attr_content[24:32]))
    file_attr_accessed = into_localtime_string(as_signed_le(attr_content[32:40]))
    file_attr_al_size = as_signed_le(attr_content[40:48])
    file_attr_act_size = as_signed_le(attr_content[48:56])
    file_attr_flags = flags.get(as_signed_le(attr_content[56:60]))
    file_attr_name_len = as_signed_le(attr_content[66:67])
    file_attr_filename = attr_content[66:67 + file_attr_name_len].decode('utf-16-le')

    result.append(file_attr_type + ' Attribute Values:')
    result.append('Flags: ' + file_attr_flags)
    result.append('Name: ' + file_attr_filename)
    result.append('Parent MFT Entry: ' + str(file_attr_parent_dir_num) + ' \t' + 'Sequence: ' + str(file_attr_parent_dir_seq))
    result.append('Allocated Size: ' + str(file_attr_al_size) + '   \t' + 'Actual Size: ' + str(file_attr_act_size))
    result.append('Created:\t' + file_attr_creation)
    result.append('File Modified:\t' + file_attr_modified)
    result.append('MFT Modified:\t' + file_attr_mft_modified)
    result.append('Accessed:\t' + file_attr_accessed)
    result.append('\n')

    # Attributes
    result.append('Attributes: ')
    # $STANDARD_INFORMATION
    attr_resident = 'Resident' if std_info_is_resident else 'Non-Resident'
    result.append('Type: ' + str(std_info_type) + ' (' + str(std_info_type_id) + '-' + str(std_info_attr_id) + ')   ' +
                  'Name: N/A   ' + attr_resident + '   size: ' + str(std_info_content_size))
    # $FILE_NAME
    attr_resident = 'Resident' if file_attr_is_resident else 'Non-Resident'
    result.append('Type: ' + str(file_attr_type) + ' (' + str(file_attr_type_id) + '-' + str(file_attr_id) + ')   ' +
                  'Name: N/A   ' + attr_resident + '   size: ' + str(file_content_size))

    # Volume attribute
    attr_start += file_attr_length
    attr_header = bytes[attr_start:attr_start+14]
    vol_attr_size = as_signed_le(attr_header[4:8])

    # Data values
    attr_start += vol_attr_size
    attr_header = bytes[attr_start:attr_start+14]
    data_attr_type_id = as_signed_le(attr_header[:4])
    data_attr_type = attr_types.get(data_attr_type_id)
    data_attr_length = as_signed_le(attr_header[4:8])
    data_attr_name_len = as_signed_le(attr_header[9:10])

    if data_attr_name_len <= 0:
        data_attr_name = 'N/A'
    else:
        data_attr_name_offset = as_signed_le(attr_header[10:12])
        data_attr_name = bytes[attr_start + data_attr_name_offset: attr_start + data_attr_name_offset + data_attr_name_len]
        data_attr_name = data_attr_name.decode('utf-16-le')
    data_attr_is_resident = True if as_signed_le(attr_header[8:9]) == 0 else False
    if data_attr_is_resident:
        data_attr_cont = bytes[attr_start+14:attr_start+22]
        data_attr_id = as_signed_le(data_attr_cont[:2])
        data_attr_content_size = as_signed_le(data_attr_cont[2:6])
        data_attr_content_offset = as_signed_le(data_attr_cont[6:8])

        result.append('Type: ' + str(data_attr_type) + ' (' + str(data_attr_type_id) + '-' + str(data_attr_id) + ')   ' +
                      'Name: ' + data_attr_name + '   Resident   size: ' + str(data_attr_content_size))
    else:
        data_attr_cont = bytes[attr_start+14:attr_start+64]
        data_attr_id = as_signed_le(data_attr_cont[:2])
        data_attr_vcn_start = as_signed_le(data_attr_cont[2:10])
        data_attr_vcn_end = as_signed_le(data_attr_cont[10:18])
        data_attr_run_offset = as_signed_le(data_attr_cont[18:20])
        data_attr_pad = as_signed_le(data_attr_cont[22:26])
        data_attr_al_size = as_signed_le(data_attr_cont[26:34])
        data_attr_act_size = as_signed_le(data_attr_cont[34:42])
        data_attr_init_size = as_signed_le(data_attr_cont[42:50])

        result.append('Type: ' + str(data_attr_type) + ' (' + str(data_attr_type_id) + '-' + str(data_attr_id) +')   ' +
                      'Name: ' + data_attr_name + '   Non-Resident   size: ' + str(data_attr_act_size) +
                      '  init_size: ' + str(data_attr_init_size))

        runlist_start = attr_start + data_attr_run_offset
        runlist_header = bytes[runlist_start]
        runlist_values = []
        runlist_first_offset = 0
        runlist_offsets = []
        while True:
            runlist_offset_bytes = (runlist_header & 0xf0) >> 4
            runlist_length_bytes = runlist_header & 0xf
            runlist = bytes[runlist_start:runlist_start + runlist_offset_bytes + runlist_length_bytes + 2]
            runlist_length = as_signed_le(runlist[1:runlist_length_bytes+1])
            runlist_offsets.append(as_signed_le(runlist[runlist_length_bytes+1:runlist_length_bytes+1 + runlist_offset_bytes]))
            if runlist_start == (attr_start + data_attr_run_offset):
                runlist_first_offset = runlist_offsets[0]
            runlist_cur_offset_sum = sum(runlist_offsets)
            for x in range(0, runlist_length):
                runlist_values.append(runlist_cur_offset_sum + x)

            if runlist[len(runlist)-1] == 0:
                break
            runlist_start = runlist_start + runlist_offset_bytes + runlist_length_bytes + 1
            runlist_header = bytes[runlist_start]

        cur_line = ''
        idx = 0
        for x in runlist_values:
            cur_line += str(x) + ' '
            idx += 1
            if idx % 8 == 0:
                result.append(cur_line)
                cur_line = ''
        if cur_line != '':
            result.append(cur_line)

    return result


def parse_runlist(runlist):
    """
    Parses a runlist of bytes
    :param runlist: runlist in byte format
    :return: a list of cluster numbers pulled from the runlist
    """
    header = runlist[0]
    header_offset = (header & 0xf0) >> 4
    header_length = header & 0xf


    print(runlist)


def into_localtime_string(windows_timestamp):
    """
    Convert a windows timestamp into istat-compatible output.

    Assumes your local host is in the EDT timezone.

    :param windows_timestamp: the struct.decoded 8-byte windows timestamp
    :return: an istat-compatible string representation of this time in EDT
    """
    dt = datetime.datetime.fromtimestamp((windows_timestamp - 116444736000000000) / 10000000)
    hms = dt.strftime('%Y-%m-%d %H:%M:%S')
    fraction = windows_timestamp % 10000000
    return hms + '.' + str(fraction) + '00 (EDT)'


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Display details of a meta-data structure (i.e. inode).')
    parser.add_argument('-o', type=int, default=0, metavar='imgoffset',
                        help='The offset of the file system in the image (in sectors)')
    parser.add_argument('-b', type=int, default=512, metavar='dev_sector_size',
                        help='The size (in bytes) of the device sectors')
    parser.add_argument('image', help='Path to an NTFS raw (dd) image')
    parser.add_argument('address', type=int, help='Meta-data number to display stats on')
    args = parser.parse_args()
    with open(args.image, 'rb') as f:
        result = istat_ntfs(f, args.address, args.b, args.o)
        for line in result:
            print(line.strip())