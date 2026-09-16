rule WEBSHELL_ASPX_ProxyShell_Aug15 {
   meta:
      description = "Webshells iisstart.aspx and Logout.aspx"
      author = "Moritz Oettle"
      reference = "https://github.com/hvs-consulting/ioc_signatures/tree/main/Proxyshell"
      date = "2021-09-04"
      modified = "2025-11-03"
      score = 75
      id = "b1e6c0f3-787f-59b8-8123-4045522047ca"
   strings:
      $g1 = "language=\"JScript\"" ascii
      $g2 = "function getErrorWord" ascii
      $g3 = "errorWord" ascii
      $g4 = "Response.Redirect" ascii
      $g5 = "function Page_Load" ascii
      $g6 = "runat=\"server\"" ascii
      $g7 = "Request[" ascii
      $g8 = "eval/*" ascii

      $s1 = "AppcacheVer" ascii  
            $s3 = "LaTkWfI64XeDAXZS6pU1KrsvLAcGH7AZOQXjrFkT816RnFYJQR" ascii

      $fp1 = "<input type=\"submit\" Value=\"Refresh This Page\""
   condition:
      filesize < 1KB
      and (
         1 of ($s*)
         or 4 of ($g*)
      )
      and not 1 of ($fp*)
}