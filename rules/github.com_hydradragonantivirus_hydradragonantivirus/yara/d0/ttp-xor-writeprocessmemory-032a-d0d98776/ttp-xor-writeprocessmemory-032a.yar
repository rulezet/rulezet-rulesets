rule TTP_XOR_WriteProcessMemory_032a {
  strings:
    $key_032a = { 54 58 [2] 66 7a [2] 60 4f [2] 4e 4f [2] 71 53 }

  condition:
    any of them
}