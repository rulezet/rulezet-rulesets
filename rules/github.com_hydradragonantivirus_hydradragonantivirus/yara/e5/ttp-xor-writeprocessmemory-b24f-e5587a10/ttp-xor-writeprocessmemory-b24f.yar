rule TTP_XOR_WriteProcessMemory_b24f {
  strings:
    $key_b24f = { e5 3d [2] d7 1f [2] d1 2a [2] ff 2a [2] c0 36 }

  condition:
    any of them
}