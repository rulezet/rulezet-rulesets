rule HKTL_NET_GUID_Altman {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/keepwn/Altman"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "21acc8af-9497-5842-90a9-7a9300585d5d"
    strings:
        $typelibguid0lo = "64cdcd2b-7356-4079-af78-e22210e66154" ascii wide
        $typelibguid1lo = "f1dee29d-ca98-46ea-9d13-93ae1fda96e1" ascii wide
        $typelibguid2lo = "33568320-56e8-4abb-83f8-548e8d6adac2" ascii wide
        $typelibguid3lo = "470ec930-70a3-4d71-b4ff-860fcb900e85" ascii wide
        $typelibguid4lo = "9514574d-6819-44f2-affa-6158ac1143b3" ascii wide
        $typelibguid5lo = "0f3a9c4f-0b11-4373-a0a6-3a6de814e891" ascii wide
        $typelibguid6lo = "9624b72e-9702-4d78-995b-164254328151" ascii wide
        $typelibguid7lo = "faae59a8-55fc-48b1-a9b5-b1759c9c1010" ascii wide
        $typelibguid8lo = "37af4988-f6f2-4f0c-aa2b-5b24f7ed3bf3" ascii wide
        $typelibguid9lo = "c82aa2fe-3332-441f-965e-6b653e088abf" ascii wide
        $typelibguid10lo = "6e531f6c-2c89-447f-8464-aaa96dbcdfff" ascii wide
        $typelibguid11lo = "231987a1-ea32-4087-8963-2322338f16f6" ascii wide
        $typelibguid12lo = "7da0d93a-a0ae-41a5-9389-42eff85bb064" ascii wide
        $typelibguid13lo = "a729f9cc-edc2-4785-9a7d-7b81bb12484c" ascii wide
        $typelibguid14lo = "55a1fd43-d23e-4d72-aadb-bbd1340a6913" ascii wide
        $typelibguid15lo = "d43f240d-e7f5-43c5-9b51-d156dc7ea221" ascii wide
        $typelibguid16lo = "c2e6c1a0-93b1-4bbc-98e6-8e2b3145db8e" ascii wide
        $typelibguid17lo = "714ae6f3-0d03-4023-b753-fed6a31d95c7" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}