rule TTP_XOR_WriteProcessMemory_be9a {
  strings:
    $key_be9a = { e9 e8 [2] db ca [2] dd ff [2] f3 ff [2] cc e3 }

  condition:
    any of them
}