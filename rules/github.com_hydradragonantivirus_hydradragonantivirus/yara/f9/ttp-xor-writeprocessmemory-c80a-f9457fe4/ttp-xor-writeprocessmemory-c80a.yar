rule TTP_XOR_WriteProcessMemory_c80a {
  strings:
    $key_c80a = { 9f 78 [2] ad 5a [2] ab 6f [2] 85 6f [2] ba 73 }

  condition:
    any of them
}