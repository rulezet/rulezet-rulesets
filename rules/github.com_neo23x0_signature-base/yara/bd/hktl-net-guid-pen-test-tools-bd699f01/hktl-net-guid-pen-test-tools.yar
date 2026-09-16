rule HKTL_NET_GUID_Pen_Test_Tools {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/awillard1/Pen-Test-Tools"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "00fb98a9-e615-5fb6-a555-4326b93e2c24"
    strings:
        $typelibguid0lo = "922e7fdc-33bf-48de-bc26-a81f85462115" ascii wide
        $typelibguid1lo = "ad5205dd-174d-4332-96d9-98b076d6fd82" ascii wide
        $typelibguid2lo = "b67e7550-f00e-48b3-ab9b-4332b1254a86" ascii wide
        $typelibguid3lo = "5e95120e-b002-4495-90a1-cd3aab2a24dd" ascii wide
        $typelibguid4lo = "295017f2-dc31-4a87-863d-0b9956c2b55a" ascii wide
        $typelibguid5lo = "abbaa2f7-1452-43a6-b98e-10b2c8c2ba46" ascii wide
        $typelibguid6lo = "a4043d4c-167b-4326-8be4-018089650382" ascii wide
        $typelibguid7lo = "51abfd75-b179-496e-86db-62ee2a8de90d" ascii wide
        $typelibguid8lo = "a06da7f8-f87e-4065-81d8-abc33cb547f8" ascii wide
        $typelibguid9lo = "ee510712-0413-49a1-b08b-1f0b0b33d6ef" ascii wide
        $typelibguid10lo = "9780da65-7e25-412e-9aa1-f77d828819d6" ascii wide
        $typelibguid11lo = "7913fe95-3ad5-41f5-bf7f-e28f080724fe" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}