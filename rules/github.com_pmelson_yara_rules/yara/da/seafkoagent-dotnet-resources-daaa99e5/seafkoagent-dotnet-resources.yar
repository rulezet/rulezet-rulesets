import "dotnet"
rule SeafKoAgent_dotnet_resources {
  meta:
    author = "Paul Melson @pmelson"
    description = "Detect .NET resource names commonly used by SeafKoAgent"
    hash = "29ec4267f11581ca0fd67ce7df8c360d4803e54f58a2ab299e026ec0df73771f"
  
  condition:
    for any item in dotnet.resources:
      ( item.name == "SeafkoAgent.Properties.Resources.resources" )
}