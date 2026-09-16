rule TTP_XOR_WriteProcessMemory_ba3f {
  strings:
    $key_ba3f = { ed 4d [2] df 6f [2] d9 5a [2] f7 5a [2] c8 46 }

  condition:
    any of them
}