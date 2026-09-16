import "dotnet"
rule NanoCore_dotnet_resources {
  meta:
    author = "Paul Melson @pmelson"
    description = "Detect .NET resource names commonly used by NanoCore"
    hash = "29591d3e7915a34c0d1c3256450bb5e2addcb3d0277d9b85954fa522909510a5"
  
  condition:
    for any item in dotnet.resources:
      ( item.name == "ClientLoaderForm.resources" )
}