rule TTP_XOR_WriteProcessMemory_090a {
  strings:
    $key_090a = { 5e 78 [2] 6c 5a [2] 6a 6f [2] 44 6f [2] 7b 73 }

  condition:
    any of them
}