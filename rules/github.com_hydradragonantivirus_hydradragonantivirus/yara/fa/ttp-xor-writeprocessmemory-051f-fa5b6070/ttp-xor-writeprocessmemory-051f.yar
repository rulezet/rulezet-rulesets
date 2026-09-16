rule TTP_XOR_WriteProcessMemory_051f {
  strings:
    $key_051f = { 52 6d [2] 60 4f [2] 66 7a [2] 48 7a [2] 77 66 }

  condition:
    any of them
}