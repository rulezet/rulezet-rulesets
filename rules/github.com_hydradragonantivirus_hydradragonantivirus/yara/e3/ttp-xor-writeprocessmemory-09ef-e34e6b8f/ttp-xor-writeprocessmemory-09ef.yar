rule TTP_XOR_WriteProcessMemory_09ef {
  strings:
    $key_09ef = { 5e 9d [2] 6c bf [2] 6a 8a [2] 44 8a [2] 7b 96 }

  condition:
    any of them
}