import "dotnet"
rule SpyGate_dotnet_resources {
  meta:
    author = "Paul Melson @pmelson"
    description = "Detect .NET resource names commonly used by SpyGate"
    hash = "67ef0a996df2e829afd58bca699342c1b694e51f7f88760d361c0372cfe5311b"
  
  condition:
    for any item in dotnet.resources:
      ( item.name == "O.A.resources" or
        item.name == "O.B.resources" or
        item.name == "O.Resources.resources" )
}