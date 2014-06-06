require "formula"

class Envchain < Formula
  homepage "https://github.com/sorah/envchain"
  head "https://github.com/sorah/envchain.git"
  url "https://github.com/sorah/envchain/archive/v0.2.0.tar.gz"
  sha1 "7d100ddbd118475ef094b25da7c361f921764e89"

  def install
    system "make", "DESTDIR=#{prefix}", "install"
  end
end
