rule TTP_XOR_WriteProcessMemory_291a {
  strings:
    $key_291a = { 7e 68 [2] 4c 4a [2] 4a 7f [2] 64 7f [2] 5b 63 }

  condition:
    any of them
}