rule TTP_XOR_WriteProcessMemory_292a {
  strings:
    $key_292a = { 7e 58 [2] 4c 7a [2] 4a 4f [2] 64 4f [2] 5b 53 }

  condition:
    any of them
}