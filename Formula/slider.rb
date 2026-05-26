class Slider < Formula
  desc "Forward proxy with multiple protocol support, DNS forwarding, and ipset management"
  homepage "https://github.com/lovitus/slider"
  version "0.16.5"
  license "GPL-3.0-only"

  on_macos do
    on_arm do
      url "https://github.com/lovitus/slider/releases/download/v0.16.5/slider_0.16.5_darwin_arm64.tar.gz"
      sha256 "c44dddc59dd6082558894a543c0c7846dce4e38f0fef501f2aa7f70a575f0baa"
    end

    on_intel do
      url "https://github.com/lovitus/slider/releases/download/v0.16.5/slider_0.16.5_darwin_amd64.tar.gz"
      sha256 "43a540afe22c43d206c5ba6de55bc32207e03d77b475569fe9241f17865526b7"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/lovitus/slider/releases/download/v0.16.5/slider_0.16.5_linux_arm64.tar.gz"
      sha256 "8d5d2c0c433a858eb22f3a4f70bbc6eff74432daa0c057529c406241dd14f8e6"
    end

    on_intel do
      url "https://github.com/lovitus/slider/releases/download/v0.16.5/slider_0.16.5_linux_amd64.tar.gz"
      sha256 "b83e6bbde865de90b92d54d3c744f3856f960aab7c2840e7ac6ff7bd72e1e8f7"
    end
  end

  def install
    bin.install "slider"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/slider --version")
  end
end
