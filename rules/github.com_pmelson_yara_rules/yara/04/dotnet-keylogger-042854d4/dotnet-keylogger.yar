import "dotnet"
rule dotnet_keylogger {
  condition:
    for any item in dotnet.resources:
      (item.name icontains "Keylogger")
}