rule TTP_XOR_WriteProcessMemory_bae8 {
  strings:
    $key_bae8 = { ed 9a [2] df b8 [2] d9 8d [2] f7 8d [2] c8 91 }

  condition:
    any of them
}