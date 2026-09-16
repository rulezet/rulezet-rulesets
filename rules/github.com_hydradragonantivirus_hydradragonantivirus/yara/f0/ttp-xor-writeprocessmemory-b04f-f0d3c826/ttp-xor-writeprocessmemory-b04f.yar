rule TTP_XOR_WriteProcessMemory_b04f {
  strings:
    $key_b04f = { e7 3d [2] d5 1f [2] d3 2a [2] fd 2a [2] c2 36 }

  condition:
    any of them
}