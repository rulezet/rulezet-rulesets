import "dotnet"
rule VoidRAT_dotnet_resources {
  meta:
    author = "Paul Melson @pmelson"
    description = "Detect .NET resource names commonly used by VoidRAT"
    hash = "02cb13ac4e6ffb8c00669a371263e69ef388e80ee78d4219b4e3cb041fe85c30"
  
  condition:
    for any item in dotnet.resources:
      ( item.name == "xClient.Properties.Resources.resources" )
}