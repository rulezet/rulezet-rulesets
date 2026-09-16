rule ARKBIRD_SOLG_APT_APT_C_23_Micropsia_Mar_2021_1: FILE {
  meta:
    description = "Detect Micropsia used by APT-C-23 (Build 2018)"
    author      = "Arkbird_SOLG"
    id          = "517a33bb-0214-588f-80e4-dc82f2552330"
    date        = "2021-03-31"
    modified    = "2021-03-31"
    reference   = "Internal Research"
    source_url  = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-03-31/APT-C-23/APT_APT_C_23_Micropsia_Mar_2021_1.yar#L1-L24"
    license_url = "N/A"
    logic_hash  = "69baab88d80ab15e08f3b08dfca45a1fee6c2e6077152906f391618713fac2ef"
    score       = 50
    quality     = 69
    tags        = "FILE"
    hash1       = "eb846bb491bea698b99eab80d58fd1f2530b0c1ee5588f7ea02ce0ce209ddb60"
    level       = "experimental"

  strings:
    $code1 = { c7 85 6c fc ff ff 12 00 00 00 8b f4 8d 85 6c fc ff ff 50 8d 8d 78 fc ff ff 51 ff 15 44 b0 66 00 3b f4 e8 80 d6 fa ff 8d 85 78 fc ff ff 50 b9 e0 83 66 00 e8 06 0d fb ff 6a 00 e8 24 0a 00 00 83 c4 04 50 e8 a2 d9 fa ff 83 c4 04 c7 85 60 fc ff ff }
    $code2 = { 68 34 4f 61 00 8d 85 cc fd ff ff 50 e8 3d 02 fd ff 83 c4 08 8b f4 6a 00 6a 00 6a 00 6a 00 8d 85 e8 fd ff ff 50 ff 15 60 b3 66 00 3b f4 e8 f2 0d fd ff 89 85 c0 fd ff ff 83 bd c0 fd ff ff 00 0f 84 49 03 00 00 8b f4 6a 00 6a 00 6a 03 6a 00 6a 00 0f b7 05 d4 83 66 00 50 8b 4d 10 51 8b 95 c0 fd ff ff 52 ff 15 58 b3 66 00 3b f4 e8 b3 0d fd ff 89 85 b4 fd ff ff 83 bd b4 fd ff ff 00 0f 84 f4 02 00 00 8b f4 6a 00 a1 d8 83 66 00 50 6a 00 6a 00 68 5c 4f 61 00 8b 4d 14 51 8d 95 cc fd ff ff 52 8b 85 b4 fd ff ff 50 ff 15 70 b3 66 00 3b f4 e8 6e 0d fd ff 89 85 a8 fd ff ff 83 bd a8 fd ff ff 00 0f 84 af 02 00 00 c7 85 9c fd ff ff 00 00 00 00 83 }
    $code3 = { 8b 85 60 fc ff ff 83 c0 01 89 85 60 fc ff ff 83 bd 60 fc ff ff 0a 7d 2a e8 3f fc fa ff 99 b9 1a 00 00 00 f7 f9 83 c2 41 88 95 57 fc ff ff 0f b6 85 57 fc ff ff 50 b9 e0 83 66 00 e8 8b 14 fb }
    $s1    = "szhttpUserAgent" fullword ascii
    $s2    = "httpUseragent" fullword ascii
    $s3    = "dwByteRead" fullword ascii
    $s4    = "%Y%m%d-%I-%M-%S"
    $s5    = "SELECT 'CREATE INDEX vacuum_db.' || substr(sql,14)  FROM sqlite_master WHERE sql LIKE 'CREATE INDEX %'"
    $s6    = "UPDATE %Q.%s SET sql = CASE WHEN type = 'trigger' THEN sqlite_rename_trigger(sql, %Q)ELSE sqlite_rename_table(sql, %Q) END, tbl_name = %Q, name = CASE WHEN type='table' THEN %Q WHEN name LIKE 'sqlite_autoindex%%' AND type='index' THEN 'sqlite_autoindex_' || %Q || substr(name,%d+18) ELSE name END WHERE tbl_name=%Q COLLATE nocase AND (type='table' OR type='index' OR type='trigger');"
    $s7    = { 25 00 6c 00 73 00 28 00 25 00 64 00 29 }
    $s8    = "Content-Type: %s\r\n"

  condition:
    uint16(0) == 0x5a4d and filesize > 50KB and 2 of ($code*) and 5 of ($s*)
}