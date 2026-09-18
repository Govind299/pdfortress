import React from "react";
import { motion } from "framer-motion";

export function FloatingPathsBackground() {
  const paths1 = Array.from({ length: 36 }, (_, i) => ({
    id: `p1-${i}`,
    d: `M-${380 - i * 5} -${189 + i * 6}C-${380 - i * 5} -${189 + i * 6} -${312 - i * 5} ${216 - i * 6} ${152 - i * 5} ${343 - i * 6}C${616 - i * 5} ${470 - i * 6} ${684 - i * 5} ${875 - i * 6} ${684 - i * 5} ${875 - i * 6}`,
    width: 0.5 + i * 0.03,
  }));

  const paths2 = Array.from({ length: 36 }, (_, i) => ({
    id: `p2-${i}`,
    d: `M-${380 + i * 5} -${189 + i * 6}C-${380 + i * 5} -${189 + i * 6} -${312 + i * 5} ${216 - i * 6} ${152 + i * 5} ${343 - i * 6}C${616 + i * 5} ${470 - i * 6} ${684 + i * 5} ${875 - i * 6} ${684 + i * 5} ${875 - i * 6}`,
    width: 0.5 + i * 0.03,
  }));

  return (
    <div
      style={{
        position: "absolute",
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        pointerEvents: "none",
        overflow: "hidden",
        zIndex: 0,
      }}
    >
      <svg
        style={{
          width: "100%",
          height: "100%",
          color: "#171717",
          opacity: 0.2,
        }}
        viewBox="0 0 696 316"
        fill="none"
        preserveAspectRatio="xMidYMid slice"
      >
        {[...paths1, ...paths2].map((path) => (
          <motion.path
            key={path.id}
            d={path.d}
            stroke="currentColor"
            strokeWidth={path.width}
            strokeOpacity={0.15}
            initial={{ pathLength: 0.3, opacity: 0.5 }}
            animate={{
              pathLength: 1,
              opacity: [0.2, 0.6, 0.2],
              pathOffset: [0, 1, 0],
            }}
            transition={{
              duration: 18 + (path.width * 5),
              repeat: Infinity,
              ease: "linear",
            }}
          />
        ))}
      </svg>
    </div>
  );
}
