rule TTP_XOR_WriteProcessMemory_200f {
  strings:
    $key_200f = { 77 7d [2] 45 5f [2] 43 6a [2] 6d 6a [2] 52 76 }

  condition:
    any of them
}