rule TTP_XOR_WriteProcessMemory_e97a {
  strings:
    $key_e97a = { be 08 [2] 8c 2a [2] 8a 1f [2] a4 1f [2] 9b 03 }

  condition:
    any of them
}