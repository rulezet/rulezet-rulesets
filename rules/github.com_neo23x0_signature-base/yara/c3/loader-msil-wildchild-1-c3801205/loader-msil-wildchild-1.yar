rule Loader_MSIL_WildChild_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the WildChild project."
        md5 = "7e6bc0ed11c2532b2ae7060327457812"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
        id = "350dd658-46c9-573b-b532-07e4b437ba8d"
    strings:
        $typelibguid1 = "2e71d5ff-ece4-4006-9e98-37bb724a7780" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}