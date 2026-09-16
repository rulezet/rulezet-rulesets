import "dotnet"
rule AsyncRAT_dotnet_resources {
  meta:
    author = "Paul Melson @pmelson"
    description = "Detect .NET resource names commonly used by AsyncRAT"
    hash = "06108b37948bfd3c26d775d93a2ff712e2739803c7eee9e7e125501a5f676f64"
  
  condition:
    for any item in dotnet.resources:
      ( item.name == "Client.Helper.FormChat.resources" )
}