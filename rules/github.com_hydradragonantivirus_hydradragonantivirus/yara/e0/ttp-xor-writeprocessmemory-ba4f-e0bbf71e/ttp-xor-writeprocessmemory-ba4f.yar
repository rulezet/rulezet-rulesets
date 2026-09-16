rule TTP_XOR_WriteProcessMemory_ba4f {
  strings:
    $key_ba4f = { ed 3d [2] df 1f [2] d9 2a [2] f7 2a [2] c8 36 }

  condition:
    any of them
}