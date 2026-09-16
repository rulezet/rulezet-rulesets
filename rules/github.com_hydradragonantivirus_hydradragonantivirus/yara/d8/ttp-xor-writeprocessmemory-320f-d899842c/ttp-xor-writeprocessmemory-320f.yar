rule TTP_XOR_WriteProcessMemory_320f {
  strings:
    $key_320f = { 65 7d [2] 57 5f [2] 51 6a [2] 7f 6a [2] 40 76 }

  condition:
    any of them
}