rule TTP_XOR_WriteProcessMemory_0de8 {
  strings:
    $key_0de8 = { 5a 9a [2] 68 b8 [2] 6e 8d [2] 40 8d [2] 7f 91 }

  condition:
    any of them
}