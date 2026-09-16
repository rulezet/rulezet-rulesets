rule TTP_XOR_WriteProcessMemory_0c1a {
  strings:
    $key_0c1a = { 5b 68 [2] 69 4a [2] 6f 7f [2] 41 7f [2] 7e 63 }

  condition:
    any of them
}