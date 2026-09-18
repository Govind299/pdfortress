import React from "react";

export function DotGridBackground({
  dotSize = 1.5,
  gap = 24,
  color = "#171717",
  opacity = 0.09,
}) {
  return (
    <div
      style={{
        position: "absolute",
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        pointerEvents: "none",
        zIndex: 0,
        overflow: "hidden",
        backgroundImage: `radial-gradient(${color} ${dotSize}px, transparent ${dotSize}px)`,
        backgroundSize: `${gap}px ${gap}px`,
        opacity: opacity,
        maskImage: "radial-gradient(ellipse at center, black 50%, transparent 85%)",
        WebkitMaskImage: "radial-gradient(ellipse at center, black 50%, transparent 85%)",
      }}
    />
  );
}
