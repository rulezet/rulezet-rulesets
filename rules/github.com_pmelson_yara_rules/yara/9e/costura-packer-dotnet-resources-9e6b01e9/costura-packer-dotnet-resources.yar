import "dotnet"
rule Costura_packer_dotnet_resources {
  meta:
    author = "Paul Melson @pmelson"
    description = "Detect .NET resoure names commonly used by Costura packer"
    hash01 = "0d8b85f3de3b266b4dfcd2892f4b0252b808f36cb8cdf594e225d45d0ca84f48"
    hash02 = "a717b5d3af3173ce9958a23f95269e2d8ccd8979445626342c32b398d4f08f8a"
    hash03 = "fc2f5146edf6f28c6cb06e280674dc43b5c1e85f61b7138b766b4607e907ee5b"
  
  condition:
    for any item in dotnet.resources:
      ( item.name == "costura.costura.dll.compressed" or
        item.name == "costura.iconlib.dll.compressed" or
        item.name == "costura.packetlib.dll.compressed" or
        item.name == "costura.packetlib.pdb.compressed" )
}