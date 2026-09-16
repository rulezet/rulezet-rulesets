import "dotnet"
rule AgentTesla_dotnet_resources {
  meta:
    author = "Paul Melson @pmelson"
    description  = "Detect .NET resource names commonly used by AgentTesla v1.x"
    hash = "e9f6784128f4f612226ffb8ff4814b88927fa281cf8b1d079b1b92198f5fcd7a"
  
  condition:
    for any item in dotnet.resources:
      ( item.name == "IELibrary.resources" or
        item.name == "firefox.resources" )
}