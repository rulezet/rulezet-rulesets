import "dotnet"
rule BlackWorm_dotnet_resources {
  meta:
    author = "Paul Melson @pmelson"
    description = "Detect .NET resource names commonly used by BlackWorm"
    hash01 = "51a081ce53b7ebb49dfc7b13027bf76b3c7c71c065d71348e3e4e7c00de15b3a"
    hash02 = "6040539f0f7f57ccb6bf059112c85538868fa834c2eaf4ab2b58c796c87aaa96"
  
  condition:
    for any item in dotnet.resources:
      ( item.name == "Stub.VanToMRAT.resources" or
        item.name == "Stub.Form3.resources" or
        item.name == "StubX.q.resources" or
        item.name == "StubX.w.resources" )
}