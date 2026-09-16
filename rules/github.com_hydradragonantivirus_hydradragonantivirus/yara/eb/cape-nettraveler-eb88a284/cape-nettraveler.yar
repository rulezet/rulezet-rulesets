rule CAPE_Nettraveler: FILE {
  meta:
    description = "NetTraveler Payload"
    author      = "kevoreilly"
    id          = "242e1c3f-5460-5393-9c07-cfab25860796"
    date        = "2022-06-09"
    modified    = "2022-06-09"
    reference   = "https://github.com/kevoreilly/CAPEv2"
    source_url  = "https://github.com/kevoreilly/CAPEv2/blob/28da61aec456106a39ce5a81c1257f7cce7fb270/data/yara/CAPE/NetTraveler.yar#L1-L14"
    license_url = "https://github.com/kevoreilly/CAPEv2/blob/28da61aec456106a39ce5a81c1257f7cce7fb270/LICENSE"
    logic_hash  = "bf5026f1a1cb3d6986a29d22657a9f1904b362391a6715d7468f8f8aca351233"
    score       = 75
    quality     = 70
    tags        = "FILE"
    cape_type   = "NetTraveler Payload"

  strings:
    $string1 = "Name:\t%s\r\nType:\t%s\r\nServer:\t%s\r\n"
    $string2 = "Password Expiried Time:"
    $string3 = "Memory: Total:%dMB,Left:%dMB (for %.2f%s)"

  condition:
    uint16(0) == 0x5A4D and all of them
}