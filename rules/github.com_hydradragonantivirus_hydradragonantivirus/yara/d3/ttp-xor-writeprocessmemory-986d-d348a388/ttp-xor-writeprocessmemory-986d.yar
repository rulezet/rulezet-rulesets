rule TTP_XOR_WriteProcessMemory_986d {
  strings:
    $key_986d = { cf 1f [2] fd 3d [2] fb 08 [2] d5 08 [2] ea 14 }

  condition:
    any of them
}