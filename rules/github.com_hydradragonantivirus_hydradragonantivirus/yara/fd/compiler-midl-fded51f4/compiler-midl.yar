rule compiler_midl {
  meta:
    author = "@tylabs"

  strings:
    $s1 = "Created by MIDL version " wide

  condition:
    any of them
}