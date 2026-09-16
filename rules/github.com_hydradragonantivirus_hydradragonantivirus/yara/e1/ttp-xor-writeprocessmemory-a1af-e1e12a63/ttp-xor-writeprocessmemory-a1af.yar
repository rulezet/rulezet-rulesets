rule TTP_XOR_WriteProcessMemory_a1af {
  strings:
    $key_a1af = { f6 dd [2] c4 ff [2] c2 ca [2] ec ca [2] d3 d6 }

  condition:
    any of them
}