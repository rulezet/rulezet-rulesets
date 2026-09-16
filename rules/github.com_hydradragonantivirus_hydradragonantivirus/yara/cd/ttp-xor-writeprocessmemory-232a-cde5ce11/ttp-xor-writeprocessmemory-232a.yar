rule TTP_XOR_WriteProcessMemory_232a {
  strings:
    $key_232a = { 74 58 [2] 46 7a [2] 40 4f [2] 6e 4f [2] 51 53 }

  condition:
    any of them
}