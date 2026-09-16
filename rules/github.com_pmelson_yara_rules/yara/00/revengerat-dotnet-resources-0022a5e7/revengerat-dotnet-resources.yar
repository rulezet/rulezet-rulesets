import "dotnet"
rule RevengeRAT_dotnet_resources {
  meta:
    author = "Paul Melson @pmelson"
    description = "Detect .NET resource names commonly used by Revenge RAT"
    hash01 = "02a30d48471d0e4b6b5e7313f00d5396979186849602ead52a06f1569c458b9c"
    hash02 = "517616106e4a3309f3833f48c08bd042e830bfa2de65fe3538a375cc43782b43"
    
  condition:
    for any item in dotnet.resources:
      ( item.name icontains "reveng" or
        item.name == "Form1.resources" )
}