// SQLite file dissection
// William Skellenger <wskellenger@intrepidcs.com>
// MIT License


#include <std/io.pat> 
#include <std/mem.pat> 
#include <std/math.pat> 



struct SQLiteHeader { 
    //The header string: "SQLite format 3\000"
    u8 header_string[16];
    //The database page size in bytes. Must be a power of two between 512 and 32768 inclusive, or the value 1 representing a page size of 65536.
    u16 db_page_size;
    //File format write version. 1 for legacy; 2 for WAL.
    u8 file_format_write_version;
    //File format read version. 1 for legacy; 2 for WAL.
    u8 file_format_read_version;
    //Bytes of unused "reserved" space at the end of each page. Usually 0.
    u8 unused_reserved_space_per_page;
    //Maximum embedded payload fraction. Must be 64.
    u8 max_embedded_payload_fraction;
    //Minimum embedded payload fraction. Must be 32.
    u8 min_embedded_payload_fraction;
    //Leaf payload fraction. Must be 32.
    u8 leaf_payload_fraction;
    //File change counter.
    u32 file_change_counter;
    //Size of the database file in pages. The "in-header database size".
    u32 database_size_in_pages;
    //Page number of the first freelist trunk page.
    u32 first_freelist_trunk_page;
    //Total number of freelist pages.
    u32 freelist_pages;
    //The schema cookie.
    u32 schema_cookie;
    //The schema format number. Supported schema formats are 1, 2, 3, and 4.
    u32 schema_format_number;
    //Default page cache size.
    u32 page_cache_size;
    //The page number of the largest root b-tree page when in auto-vacuum or incremental-vacuum modes, or zero otherwise.
    u32 largest_root_page;
    //The database text encoding. A value of 1 means UTF-8. A value of 2 means UTF-16le. A value of 3 means UTF-16be.
    u32 db_text_encoding;
    //The "user version" as read and set by the user_version pragma.
    u32 user_version;
    //True (non-zero) for incremental-vacuum mode. False (zero) otherwise.
    u32 incrememtal_vacuum_mode;
    //The "Application ID" set by PRAGMA application_id.
    u32 application_id;
    //Reserved for expansion. Must be zero.
    u8 reserved[20];
    //The version-valid-for number.
    u32 sqlite_version_valid_for;
    //SQLITE_VERSION_NUMBER
    u32 sqlite_version_number;
}; 

SQLiteHeader header @ 0x00;
