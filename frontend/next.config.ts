import type { NextConfig } from "next";
const apiOrigin = (process.env.ASSESSMENT_API_ORIGIN ?? "https://web-assessment-workbench-api.onrender.com").replace(/\/$/, "");
const config: NextConfig = {
  distDir: ".next-build",
  async rewrites() {
    return [{ source: "/backend/:path*", destination: `${apiOrigin}/:path*` }];
  },
};
export default config;
