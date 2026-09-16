rule TTP_XOR_WriteProcessMemory_dd1c {
  strings:
    $key_dd1c = { 8a 6e [2] b8 4c [2] be 79 [2] 90 79 [2] af 65 }

  condition:
    any of them
}