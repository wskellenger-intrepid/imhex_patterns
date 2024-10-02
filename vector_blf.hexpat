// BLF File parser for imHex
// October 2, 2024
// William Skellenger: wskellenger@intrepidcs.com
// -----
// Credit to Tobias Lorenz <tobias.lorenz@gmx.net> for the excellent vector_blf library,
// where these definitions came from: https://bitbucket.org/tobylorenz/vector_blf.git

#pragma pattern_limit 2000000
#pragma array_limit 200000

#include <type/magic.pat>
#include <type/types/c.pat>
#include <std/mem.pat>
#include <std/math.pat>

s32 LOBJ_NOT_FOUND = -1;
u32 mismatched_length_records_count = 0;

enum RecordType:u32 {
    UNKNOWN = 0, /**< unknown object */
    CAN_MESSAGE = 1, /**< CAN message object */
    CAN_ERROR = 2, /**< CAN error frame object */
    CAN_OVERLOAD = 3, /**< CAN overload frame object */
    CAN_STATISTIC = 4, /**< CAN driver statistics object */
    APP_TRIGGER = 5, /**< application trigger object */
    ENV_INTEGER = 6, /**< environment integer object */
    ENV_DOUBLE = 7, /**< environment double object */
    ENV_STRING = 8, /**< environment string object */
    ENV_DATA = 9, /**< environment data object */
    LOG_CONTAINER = 10, /**< container object */
    LIN_MESSAGE = 11, /**< LIN message object */
    LIN_CRC_ERROR = 12, /**< LIN CRC error object */
    LIN_DLC_INFO = 13, /**< LIN DLC info object */
    LIN_RCV_ERROR = 14, /**< LIN receive error object */
    LIN_SND_ERROR = 15, /**< LIN send error object */
    LIN_SLV_TIMEOUT = 16, /**< LIN slave timeout object */
    LIN_SCHED_MODCH = 17, /**< LIN scheduler mode change object */
    LIN_SYN_ERROR = 18, /**< LIN sync error object */
    LIN_BAUDRATE = 19, /**< LIN baudrate event object */
    LIN_SLEEP = 20, /**< LIN sleep mode event object */
    LIN_WAKEUP = 21, /**< LIN wakeup event object */
    MOST_SPY = 22, /**< MOST spy message object */
    MOST_CTRL = 23, /**< MOST control message object */
    MOST_LIGHTLOCK = 24, /**< MOST light lock object */
    MOST_STATISTIC = 25, /**< MOST statistic object */
    Reserved26 = 26, /**< reserved */
    Reserved27 = 27, /**< reserved */
    Reserved28 = 28, /**< reserved */
    FLEXRAY_DATA = 29, /**< FLEXRAY data object */
    FLEXRAY_SYNC = 30, /**< FLEXRAY sync object */
    CAN_DRIVER_ERROR = 31, /**< CAN driver error object */
    MOST_PKT = 32, /**< MOST Packet */
    MOST_PKT2 = 33, /**< MOST Packet including original timestamp */
    MOST_HWMODE = 34, /**< MOST hardware mode event */
    MOST_REG = 35, /**< MOST register data (various chips) */
    MOST_GENREG = 36, /**< MOST register data (MOST register) */
    MOST_NETSTATE = 37, /**< MOST NetState event */
    MOST_DATALOST = 38, /**< MOST data lost */
    MOST_TRIGGER = 39, /**< MOST trigger */
    FLEXRAY_CYCLE = 40, /**< FLEXRAY V6 start cycle object */
    FLEXRAY_MESSAGE = 41, /**< FLEXRAY V6 message object */
    LIN_CHECKSUM_INFO = 42, /**< LIN checksum info event object */
    LIN_SPIKE_EVENT = 43, /**< LIN spike event object */
    CAN_DRIVER_SYNC = 44, /**< CAN driver hardware sync */
    FLEXRAY_STATUS = 45, /**< FLEXRAY status event object */
    GPS_EVENT = 46, /**< GPS event object */
    FR_ERROR = 47, /**< FLEXRAY error event object */
    FR_STATUS = 48, /**< FLEXRAY status event object */
    FR_STARTCYCLE = 49, /**< FLEXRAY start cycle event object */
    FR_RCVMESSAGE = 50, /**< FLEXRAY receive message event object */
    REALTIMECLOCK = 51, /**< Realtime clock object */
    Reserved52 = 52, /**< this object ID is available for the future */
    Reserved53 = 53, /**< this object ID is available for the future */
    LIN_STATISTIC = 54, /**< LIN statistic event object */
    J1708_MESSAGE = 55, /**< J1708 message object */
    J1708_VIRTUAL_MSG = 56, /**< J1708 message object with more than 21 data bytes */
    LIN_MESSAGE2 = 57, /**< LIN frame object - extended */
    LIN_SND_ERROR2 = 58, /**< LIN transmission error object - extended */
    LIN_SYN_ERROR2 = 59, /**< LIN sync error object - extended */
    LIN_CRC_ERROR2 = 60, /**< LIN checksum error object - extended */
    LIN_RCV_ERROR2 = 61, /**< LIN receive error object */
    LIN_WAKEUP2 = 62, /**< LIN wakeup event object  - extended */
    LIN_SPIKE_EVENT2 = 63, /**< LIN spike event object - extended */
    LIN_LONG_DOM_SIG = 64, /**< LIN long dominant signal object */
    APP_TEXT = 65, /**< text object */
    FR_RCVMESSAGE_EX = 66, /**< FLEXRAY receive message ex event object */
    MOST_STATISTICEX = 67, /**< MOST extended statistic event */
    MOST_TXLIGHT = 68, /**< MOST TxLight event */
    MOST_ALLOCTAB = 69, /**< MOST Allocation table event */
    MOST_STRESS = 70, /**< MOST Stress event */
    ETHERNET_FRAME = 71, /**< Ethernet frame object */
    SYS_VARIABLE = 72, /**< system variable object */
    CAN_ERROR_EXT = 73, /**< CAN error frame object (extended) */
    CAN_DRIVER_ERROR_EXT = 74, /**< CAN driver error object (extended) */
    LIN_LONG_DOM_SIG2 = 75, /**< LIN long dominant signal object - extended */
    MOST_150_MESSAGE = 76, /**< MOST150 Control channel message */
    MOST_150_PKT = 77, /**< MOST150 Asynchronous channel message */
    MOST_ETHERNET_PKT = 78, /**< MOST Ethernet channel message */
    MOST_150_MESSAGE_FRAGMENT = 79, /**< Partial transmitted MOST50/150 Control channel message */
    MOST_150_PKT_FRAGMENT = 80, /**< Partial transmitted MOST50/150 data packet on asynchronous channel */
    MOST_ETHERNET_PKT_FRAGMENT = 81, /**< Partial transmitted MOST Ethernet packet on asynchronous channel */
    MOST_SYSTEM_EVENT = 82, /**< Event for various system states on MOST */
    MOST_150_ALLOCTAB = 83, /**< MOST50/150 Allocation table event */
    MOST_50_MESSAGE = 84, /**< MOST50 Control channel message */
    MOST_50_PKT = 85, /**< MOST50 Asynchronous channel message */
    CAN_MESSAGE2 = 86, /**< CAN message object - extended */
    LIN_UNEXPECTED_WAKEUP = 87,
    LIN_SHORT_OR_SLOW_RESPONSE = 88,
    LIN_DISTURBANCE_EVENT = 89,
    SERIAL_EVENT = 90,
    OVERRUN_ERROR = 91, /**< driver overrun event */
    EVENT_COMMENT = 92,
    WLAN_FRAME = 93,
    WLAN_STATISTIC = 94,
    MOST_ECL = 95, /**< MOST Electrical Control Line event */
    GLOBAL_MARKER = 96,
    AFDX_FRAME = 97,
    AFDX_STATISTIC = 98,
    KLINE_STATUSEVENT = 99, /**< E.g. wake-up pattern */
    CAN_FD_MESSAGE = 100, /**< CAN FD message object */
    CAN_FD_MESSAGE_64 = 101, /**< CAN FD message object */
    ETHERNET_RX_ERROR = 102, /**< Ethernet RX error object */
    ETHERNET_STATUS = 103, /**< Ethernet status object */
    CAN_FD_ERROR_64 = 104, /**< CAN FD Error Frame object */
    LIN_SHORT_OR_SLOW_RESPONSE2 = 105,
    AFDX_STATUS = 106, /**< AFDX status object */
    AFDX_BUS_STATISTIC = 107, /**< AFDX line-dependent busstatistic object */
    Reserved108 = 108,
    AFDX_ERROR_EVENT = 109, /**< AFDX asynchronous error event */
    A429_ERROR = 110, /**< A429 error object */
    A429_STATUS = 111, /**< A429 status object */
    A429_BUS_STATISTIC = 112, /**< A429 busstatistic object */
    A429_MESSAGE = 113, /**< A429 Message */
    ETHERNET_STATISTIC = 114, /**< Ethernet statistic object */
    Unknown115 = 115,
    Reserved116 = 116,
    Reserved117 = 117,
    TEST_STRUCTURE = 118, /**< Event for test execution flow */
    DIAG_REQUEST_INTERPRETATION = 119, /**< Event for correct interpretation of diagnostic requests */
    ETHERNET_FRAME_EX = 120, /**< Ethernet packet extended object */
    ETHERNET_FRAME_FORWARDED = 121, /**< Ethernet packet forwarded object */
    ETHERNET_ERROR_EX = 122, /**< Ethernet error extended object */
    ETHERNET_ERROR_FORWARDED = 123, /**< Ethernet error forwarded object */
    FUNCTION_BUS = 124, /**< FunctionBus object */
    DATA_LOST_BEGIN = 125, /**< Data lost begin */
    DATA_LOST_END = 126, /**< Data lost end */
    WATER_MARK_EVENT = 127, /**< Watermark event */
    TRIGGER_CONDITION = 128, /**< Trigger Condition event */
    CAN_SETTING_CHANGED = 129, /**< CAN Settings Changed object */
    DISTRIBUTED_OBJECT_MEMBER = 130, /**< Distributed object member (communication setup) */
    ATTRIBUTE_EVENT = 131, /**< ATTRIBUTE event (communication setup) */
};

fn get_record_type_name(RecordType type) {   
    match (type) {
        (RecordType::A429_BUS_STATISTIC): return "A429 busstatistic object";
        (RecordType::A429_ERROR): return "A429 error object";
        (RecordType::A429_MESSAGE): return "A429 Message";
        (RecordType::A429_STATUS): return "A429 status object";
        (RecordType::AFDX_BUS_STATISTIC): return "AFDX line-dependent busstatistic object";
        (RecordType::AFDX_ERROR_EVENT): return "AFDX asynchronous error event";
        (RecordType::AFDX_FRAME): return "AFDX_FRAME";
        (RecordType::AFDX_STATISTIC): return "AFDX_STATISTIC";
        (RecordType::AFDX_STATUS): return "AFDX status object";
        (RecordType::APP_TEXT): return "text object";
        (RecordType::APP_TRIGGER): return "application trigger object";
        (RecordType::ATTRIBUTE_EVENT): return "ATTRIBUTE event (communication setup)";
        (RecordType::CAN_DRIVER_ERROR): return "CAN driver error object";
        (RecordType::CAN_DRIVER_ERROR_EXT): return "CAN driver error object (extended)";
        (RecordType::CAN_DRIVER_SYNC): return "CAN driver hardware sync";
        (RecordType::CAN_ERROR): return "CAN error frame object";
        (RecordType::CAN_ERROR_EXT): return "CAN error frame object (extended)";
        (RecordType::CAN_FD_ERROR_64): return "CAN FD Error Frame object";
        (RecordType::CAN_FD_MESSAGE): return "CAN FD message object";
        (RecordType::CAN_FD_MESSAGE_64): return "CAN FD message object";
        (RecordType::CAN_MESSAGE): return "CAN message object";
        (RecordType::CAN_MESSAGE2): return "CAN message object - extended";
        (RecordType::CAN_OVERLOAD): return "CAN overload frame object";
        (RecordType::CAN_SETTING_CHANGED): return "CAN Settings Changed object";
        (RecordType::CAN_STATISTIC): return "CAN driver statistics object";
        (RecordType::DATA_LOST_BEGIN): return "Data lost begin";
        (RecordType::DATA_LOST_END): return "Data lost end";
        (RecordType::DIAG_REQUEST_INTERPRETATION): return "Event for correct interpretation of diagnostic requests";
        (RecordType::DISTRIBUTED_OBJECT_MEMBER): return "Distributed object member (communication setup)";
        (RecordType::ENV_DATA): return "environment data object";
        (RecordType::ENV_DOUBLE): return "environment double object";
        (RecordType::ENV_INTEGER): return "environment integer object";
        (RecordType::ENV_STRING): return "environment string object";
        (RecordType::ETHERNET_ERROR_EX): return "Ethernet error extended object";
        (RecordType::ETHERNET_ERROR_FORWARDED): return "Ethernet error forwarded object";
        (RecordType::ETHERNET_FRAME): return "Ethernet frame object";
        (RecordType::ETHERNET_FRAME_EX): return "Ethernet packet extended object";
        (RecordType::ETHERNET_FRAME_FORWARDED): return "Ethernet packet forwarded object";
        (RecordType::ETHERNET_RX_ERROR): return "Ethernet RX error object";
        (RecordType::ETHERNET_STATISTIC): return "Ethernet statistic object";
        (RecordType::ETHERNET_STATUS): return "Ethernet status object";
        (RecordType::EVENT_COMMENT): return "EVENT_COMMENT";
        (RecordType::FLEXRAY_CYCLE): return "FLEXRAY V6 start cycle object";
        (RecordType::FLEXRAY_DATA): return "FLEXRAY data object";
        (RecordType::FLEXRAY_MESSAGE): return "FLEXRAY V6 message object";
        (RecordType::FLEXRAY_STATUS): return "FLEXRAY status event object";
        (RecordType::FLEXRAY_SYNC): return "FLEXRAY sync object";
        (RecordType::FR_ERROR): return "FLEXRAY error event object";
        (RecordType::FR_RCVMESSAGE): return "FLEXRAY receive message event object";
        (RecordType::FR_RCVMESSAGE_EX): return "FLEXRAY receive message ex event object";
        (RecordType::FR_STARTCYCLE): return "FLEXRAY start cycle event object";
        (RecordType::FR_STATUS): return "FLEXRAY status event object";
        (RecordType::FUNCTION_BUS): return "FunctionBus object";
        (RecordType::GLOBAL_MARKER): return "GLOBAL_MARKER";
        (RecordType::GPS_EVENT): return "GPS event object";
        (RecordType::J1708_MESSAGE): return "J1708 message object";
        (RecordType::J1708_VIRTUAL_MSG): return "J1708 message object with more than 21 data bytes";
        (RecordType::KLINE_STATUSEVENT): return "E.g. wake-up pattern";
        (RecordType::LIN_BAUDRATE): return "LIN baudrate event object";
        (RecordType::LIN_CHECKSUM_INFO): return "LIN checksum info event object";
        (RecordType::LIN_CRC_ERROR): return "LIN CRC error object";
        (RecordType::LIN_CRC_ERROR2): return "LIN checksum error object - extended";
        (RecordType::LIN_DISTURBANCE_EVENT): return "LIN_DISTURBANCE_EVENT";
        (RecordType::LIN_DLC_INFO): return "LIN DLC info object";
        (RecordType::LIN_LONG_DOM_SIG): return "LIN long dominant signal object";
        (RecordType::LIN_LONG_DOM_SIG2): return "LIN long dominant signal object - extended";
        (RecordType::LIN_MESSAGE): return "LIN message object";
        (RecordType::LIN_MESSAGE2): return "LIN frame object - extended";
        (RecordType::LIN_RCV_ERROR): return "LIN receive error object";
        (RecordType::LIN_RCV_ERROR2): return "LIN receive error object";
        (RecordType::LIN_SCHED_MODCH): return "LIN scheduler mode change object";
        (RecordType::LIN_SHORT_OR_SLOW_RESPONSE): return "LIN_SHORT_OR_SLOW_RESPONSE";
        (RecordType::LIN_SHORT_OR_SLOW_RESPONSE2): return "LIN_SHORT_OR_SLOW_RESPONSE2";
        (RecordType::LIN_SLEEP): return "LIN sleep mode event object";
        (RecordType::LIN_SLV_TIMEOUT): return "LIN slave timeout object";
        (RecordType::LIN_SND_ERROR): return "LIN send error object";
        (RecordType::LIN_SND_ERROR2): return "LIN transmission error object - extended";
        (RecordType::LIN_SPIKE_EVENT): return "LIN spike event object";
        (RecordType::LIN_SPIKE_EVENT2): return "LIN spike event object - extended";
        (RecordType::LIN_STATISTIC): return "LIN statistic event object";
        (RecordType::LIN_SYN_ERROR): return "LIN sync error object";
        (RecordType::LIN_SYN_ERROR2): return "LIN sync error object - extended";
        (RecordType::LIN_UNEXPECTED_WAKEUP): return "LIN_UNEXPECTED_WAKEUP";
        (RecordType::LIN_WAKEUP): return "LIN wakeup event object";
        (RecordType::LIN_WAKEUP2): return "LIN wakeup event object  - extended";
        (RecordType::LOG_CONTAINER): return "container object";
        (RecordType::MOST_150_ALLOCTAB): return "MOST50/150 Allocation table event";
        (RecordType::MOST_150_MESSAGE): return "MOST150 Control channel message";
        (RecordType::MOST_150_MESSAGE_FRAGMENT): return "Partial transmitted MOST50/150 Control channel message";
        (RecordType::MOST_150_PKT): return "MOST150 Asynchronous channel message";
        (RecordType::MOST_150_PKT_FRAGMENT): return "Partial transmitted MOST50/150 data packet on asynchronous channel";
        (RecordType::MOST_50_MESSAGE): return "MOST50 Control channel message";
        (RecordType::MOST_50_PKT): return "MOST50 Asynchronous channel message";
        (RecordType::MOST_ALLOCTAB): return "MOST Allocation table event";
        (RecordType::MOST_CTRL): return "MOST control message object";
        (RecordType::MOST_DATALOST): return "MOST data lost";
        (RecordType::MOST_ECL): return "MOST Electrical Control Line event";
        (RecordType::MOST_ETHERNET_PKT): return "MOST Ethernet channel message";
        (RecordType::MOST_ETHERNET_PKT_FRAGMENT): return "Partial transmitted MOST Ethernet packet on asynchronous channel";
        (RecordType::MOST_GENREG): return "MOST register data (MOST register)";
        (RecordType::MOST_HWMODE): return "MOST hardware mode event";
        (RecordType::MOST_LIGHTLOCK): return "MOST light lock object";
        (RecordType::MOST_NETSTATE): return "MOST NetState event";
        (RecordType::MOST_PKT): return "MOST Packet";
        (RecordType::MOST_PKT2): return "MOST Packet including original timestamp";
        (RecordType::MOST_REG): return "MOST register data (various chips)";
        (RecordType::MOST_SPY): return "MOST spy message object";
        (RecordType::MOST_STATISTIC): return "MOST statistic object";
        (RecordType::MOST_STATISTICEX): return "MOST extended statistic event";
        (RecordType::MOST_STRESS): return "MOST Stress event";
        (RecordType::MOST_SYSTEM_EVENT): return "Event for various system states on MOST";
        (RecordType::MOST_TRIGGER): return "MOST trigger";
        (RecordType::MOST_TXLIGHT): return "MOST TxLight event";
        (RecordType::OVERRUN_ERROR): return "driver overrun event";
        (RecordType::REALTIMECLOCK): return "Realtime clock object";
        (RecordType::Reserved108): return "Reserved108";
        (RecordType::Reserved116): return "Reserved116";
        (RecordType::Reserved117): return "Reserved117";
        (RecordType::Reserved26): return "Reserved26";
        (RecordType::Reserved27): return "Reserved27";
        (RecordType::Reserved28): return "Reserved28";
        (RecordType::Reserved52): return "Reserved52";
        (RecordType::Reserved53): return "Reserved53";
        (RecordType::SERIAL_EVENT): return "SERIAL_EVENT";
        (RecordType::SYS_VARIABLE): return "system variable object";
        (RecordType::TEST_STRUCTURE): return "Event for test execution flow";
        (RecordType::TRIGGER_CONDITION): return "Trigger Condition event";
        (RecordType::UNKNOWN): return "unknown object";
        (RecordType::Unknown115): return "Unknown115";
        (RecordType::WATER_MARK_EVENT): return "Watermark event";
        (RecordType::WLAN_FRAME): return "WLAN_FRAME";
        (RecordType::WLAN_STATISTIC): return "WLAN_STATISTIC";
        (_): return "Unsupported record type";
    }
};

fn get_formatted_record_type(RecordType type)
{
    return std::format("({}) {}", u32(type), get_record_type_name(type));
};



/** system time */
struct SYSTEMTIME {
    uint16_t year;
    uint16_t month;
    uint16_t dayOfWeek; /** day of week (0=Sunday, 6=Saturday) */
    uint16_t day;
    uint16_t hour;
    uint16_t minute;
    uint16_t second;
    uint16_t milliseconds;
};

struct BLFFileSignature {
	type::Magic<"LOGG"> signature;
	u32 statisticsSize;
	u32 apiNumber;
	u8 applicationId;
	u8 compressionLevel;
	u8 applicationMajor;
	u8 applicationMinor;
	u64 fileSize;
	u64 uncompressedFileSize;
	u32 objectCount;
	u32 applicationBuild;
	SYSTEMTIME measurementStartTime;
	SYSTEMTIME lastObjectTime;
	u64 restorePointsOffset;
	u32 reservedFileStatistics[16];
};

struct BLFOBJHeaderBase {
    type::Magic<"LOBJ"> signature;
    u16 headerSize;
    u16 headerVersion;
    u32 objectSize [[comment("The length of all data, including the header")]];
    RecordType objectType [[format("get_formatted_record_type")]];
};

struct BLFOBJHeader {
    BLFOBJHeaderBase base;
    u32 objectFlags;
    u16 clientIndex;
    u16 objectVersion;
    u64 objectTimeStamp;
};

struct BLFOBJHeader2 {
    BLFOBJHeaderBase base;
    u32 objectFlags;
    u8 timeStampStatus;
    u8 reservedObjectHeader;
    u16 objectVersion;
    u64 objectTimeStamp;
    u64 originalTimeStamp;
};


int32_t calculated_object_length = 0;
struct BLFRecord {
    BLFOBJHeader header;
    calculated_object_length = get_next_LOBJ_position_offset();

    if (calculated_object_length == LOBJ_NOT_FOUND)
    {
        std::print("INFO: Can't locate any more LOBJ markers, we're done. (at: {})", $);
        u8 objectdata[std::mem::size()-$];  //we are done
        
        if (mismatched_length_records_count)
        {
            std::print("INFO: Found {} records with mismatched lengths.", mismatched_length_records_count);
        }
                
        break;
    }
    else
    {
        //verbose error reporting
        if (calculated_object_length + sizeof(header) != header.base.objectSize)
        {
            mismatched_length_records_count += 1;
            std::print("WARNING: Calculated object length: {} doesn't equal: {} (at: {})", calculated_object_length + sizeof(header), header.base.objectSize, $);
        }        
        u8 objectdata[calculated_object_length];    
    }
};

fn get_next_LOBJ_position_offset() {
    s32 offset = 0;
    //look through the next 1000 bytes and try to find the next LOBJ value
    s32 pos = std::mem::find_sequence_in_range(0, $, std::mem::size(), 'L', 'O', 'B', 'J');
    
    if ((pos > std::mem::size()) || (pos == LOBJ_NOT_FOUND))
        offset = LOBJ_NOT_FOUND;
    else
        offset = pos - $;

    //std::print("pos {} $ {}", pos, $);
    return offset;
};


BLFFileSignature BLFFileSignature @ 0x00;
BLFRecord records[while(!std::mem::eof())] @ $;