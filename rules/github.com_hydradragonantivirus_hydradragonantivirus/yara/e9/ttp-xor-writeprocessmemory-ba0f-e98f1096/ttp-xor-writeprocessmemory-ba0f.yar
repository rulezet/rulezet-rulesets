rule TTP_XOR_WriteProcessMemory_ba0f {
  strings:
    $key_ba0f = { ed 7d [2] df 5f [2] d9 6a [2] f7 6a [2] c8 76 }

  condition:
    any of them
}