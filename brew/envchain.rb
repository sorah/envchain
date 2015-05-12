require "formula"

class Envchain < Formula
  homepage "https://github.com/sorah/envchain"
  head "https://github.com/sorah/envchain.git"
  url "https://github.com/sorah/envchain/archive/v0.3.0.tar.gz"
  sha1 "17981bebd628575d8fd61ae3ff29612c04fdc828"
  version '0.3.0'

  def install
    system "make", "DESTDIR=#{prefix}", "install"
  end
end
