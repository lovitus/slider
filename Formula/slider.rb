class Slider < Formula
  desc "Forward proxy with multiple protocol support, DNS forwarding, and ipset management"
  homepage "https://github.com/lovitus/slider"
  version "0.16.5"
  license "GPL-3.0-only"

  on_macos do
    on_arm do
      url "https://github.com/lovitus/slider/releases/download/v0.16.5/slider_0.16.5_darwin_arm64.tar.gz"
      sha256 "9d72e018f619468ef5288d36b500806b55d9f2b80ec30a39804cca7061e419fa"
    end

    on_intel do
      url "https://github.com/lovitus/slider/releases/download/v0.16.5/slider_0.16.5_darwin_amd64.tar.gz"
      sha256 "aa5356455d0752e5d607bec496d1e22310f370a01799809cdf5dfcdeb8100f70"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/lovitus/slider/releases/download/v0.16.5/slider_0.16.5_linux_arm64.tar.gz"
      sha256 "5b055fcef4f9e6340ef5ac52bd379216d0cd6785476851408d2b6e44e9bb154c"
    end

    on_intel do
      url "https://github.com/lovitus/slider/releases/download/v0.16.5/slider_0.16.5_linux_amd64.tar.gz"
      sha256 "fcda3228ea5a2b725bdd85afbe5b3303a0cd5f5ba1aef6447baab43d33111619"
    end
  end

  def install
    bin.install "slider"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/slider --version")
  end
end
