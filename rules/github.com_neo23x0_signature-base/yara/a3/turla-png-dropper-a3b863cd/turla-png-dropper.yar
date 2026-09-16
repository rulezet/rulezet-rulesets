rule turla_png_dropper {
    meta:
        author = "Ben Humphrey"
        description = "Detects the PNG Dropper used by the Turla group"
        reference = "https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/november/turla-png-dropper-is-back/"
        date = "2018/11/23"
        hash1 = "6ed939f59476fd31dc4d99e96136e928fbd88aec0d9c59846092c0e93a3c0e27"
        id = "459f17c8-0eae-5736-8c7c-286625dc158f"
    strings:
        $api0 = "GdiplusStartup"
        $api1 = "GdipAlloc"
        $api2 = "GdipCreateBitmapFromStreamICM"
        $api3 = "GdipBitmapLockBits"
        $api4 = "GdipGetImageWidth"
        $api5 = "GdipGetImageHeight"
        $api6 = "GdiplusShutdown"
        $code32 = {
            8B 46 3C                           B9 0B 01 00 00                     66 39 4C 30 18                     8B 44 30 28                        6A 00                              B9 AF BE AD DE                     51                                 51                                 03 C6                              56                                 FF D0                          }

        $code64 = {
            48 63 43 3C                        B9 0B 01 00 00                     BA AF BE AD DE                     66 39 4C 18 18                     8B 44 18 28                        45 33 C9                           44 8B C2                           48 8B CB                           48 03 C3                           FF D0                          }
        condition:
        (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and
        all of ($api*) and
        1 of ($code*)
}