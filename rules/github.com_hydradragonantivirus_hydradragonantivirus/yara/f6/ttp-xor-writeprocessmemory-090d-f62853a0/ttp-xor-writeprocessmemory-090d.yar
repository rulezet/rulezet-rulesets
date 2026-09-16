rule TTP_XOR_WriteProcessMemory_090d {
  strings:
    $key_090d = { 5e 7f [2] 6c 5d [2] 6a 68 [2] 44 68 [2] 7b 74 }

  condition:
    any of them
}