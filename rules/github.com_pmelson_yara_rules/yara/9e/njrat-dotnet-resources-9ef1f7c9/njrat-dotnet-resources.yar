import "dotnet"
rule njRat_dotnet_resources {
  meta:
    author = "Paul Melson @pmelson"
    description = "Detect .NET resource names commonly used by njRat"
    hash01 = "0597ec69b22596a4c3639c9efaa8695ad534776f2f1844225129578874d0b51f"
    hash02 = "34feb3ff474a7b644f497a133a78a220a496a54fd597b097eabce803d2a6c16f"
  
  condition:
    for any item in dotnet.resources:
      ( item.name == "Stub.Resources.resources" or
        item.name == "Hacking.Explorer1.resources" )
}