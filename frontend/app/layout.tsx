import type { Metadata } from "next";
import "./style.css";
export const metadata: Metadata = { title: "Web Assessment Workbench", description: "Evidence-first authorized web security assessment" };
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) { return <html lang="en"><body>{children}</body></html>; }
