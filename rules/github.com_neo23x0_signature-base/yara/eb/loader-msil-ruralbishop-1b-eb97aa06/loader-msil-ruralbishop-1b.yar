rule Loader_MSIL_RuralBishop_1b
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public RuralBishop project."
        md5 = "09bdbad8358b04994e2c04bb26a160ef"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
        id = "55a060ef-74e2-50d9-9090-558aaa04d97d"
    strings:
        $typelibguid1 = "FE4414D9-1D7E-4EEB-B781-D278FE7A5619" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}