import React, { useEffect, useRef } from "react";

export function BackgroundRippleEffect() {
  const containerRef = useRef(null);
  const canvasRef = useRef(null);
  const mouseRef = useRef({ x: -1000, y: -1000 });
  const ripplesRef = useRef([]);

  useEffect(() => {
    const container = containerRef.current;
    const canvas = canvasRef.current;
    if (!container || !canvas) return;
    const ctx = canvas.getContext("2d");

    let animationFrameId;
    const cellSize = 48; // Size of grid boxes

    const resize = () => {
      if (!container) return;
      canvas.width = window.innerWidth;
      canvas.height = container.clientHeight;
    };

    const resizeObserver = new ResizeObserver(resize);
    resizeObserver.observe(container);
    window.addEventListener("resize", resize);
    resize();

    const handleMouseMove = (e) => {
      const rect = container.getBoundingClientRect();
      mouseRef.current = {
        x: e.clientX - rect.left,
        y: e.clientY - rect.top,
      };
    };

    const handleClick = (e) => {
      // Ignore click if user clicked on buttons, inputs, links, navbar, or upload card
      if (
        e.target.closest("button") ||
        e.target.closest("input") ||
        e.target.closest("a") ||
        e.target.closest(".geist-navbar") ||
        e.target.closest(".max-w-xl") // FileUploadCard container
      ) {
        return;
      }

      const rect = container.getBoundingClientRect();
      if (e.clientY >= rect.top && e.clientY <= rect.bottom) {
        ripplesRef.current.push({
          x: e.clientX - rect.left,
          y: e.clientY - rect.top,
          radius: 0,
          maxRadius: Math.max(window.innerWidth, rect.height) * 0.85,
          speed: 11,
          opacity: 1,
        });
      }
    };

    window.addEventListener("mousemove", handleMouseMove);
    window.addEventListener("click", handleClick);

    const render = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      const cols = Math.ceil(canvas.width / cellSize);
      const rows = Math.ceil(canvas.height / cellSize);
      const mouse = mouseRef.current;

      // Update active ripples
      ripplesRef.current.forEach((r) => {
        r.radius += r.speed;
        r.opacity = Math.max(0, 1 - r.radius / r.maxRadius);
      });
      ripplesRef.current = ripplesRef.current.filter((r) => r.opacity > 0);

      // Draw Grid Tiles with native edge and bottom falloff
      for (let r = 0; r < rows; r++) {
        for (let c = 0; c < cols; c++) {
          const x = c * cellSize;
          const y = r * cellSize;
          const centerX = x + cellSize / 2;
          const centerY = y + cellSize / 2;

          // Calculate normalized position relative to canvas
          const normX = Math.abs((centerX - canvas.width / 2) / (canvas.width / 2)); // 0 at center, 1 at left/right edges
          const normY = centerY / canvas.height; // 0 at top, 1 at bottom

          // Edge fade (Left/Right) & Bottom Fade factors
          const fadeX = Math.max(0, Math.cos(normX * (Math.PI / 2)));
          const fadeY = Math.max(0, 1 - Math.pow(normY, 2.2));
          const cellAlpha = Math.pow(fadeX * fadeY, 1.3);

          if (cellAlpha <= 0.005) continue; // Skip rendering completely invisible outer cells

          // Calculate distance from mouse hover
          const distMouse = Math.hypot(centerX - mouse.x, centerY - mouse.y);
          const isHovered = distMouse < cellSize * 1.5;

          // Calculate ripple wave hit
          let rippleIntensity = 0;
          ripplesRef.current.forEach((rip) => {
            const distRip = Math.hypot(centerX - rip.x, centerY - rip.y);
            const waveDiff = Math.abs(distRip - rip.radius);
            if (waveDiff < cellSize * 1.2) {
              const waveStrength = (1 - waveDiff / (cellSize * 1.2)) * rip.opacity;
              rippleIntensity = Math.max(rippleIntensity, waveStrength);
            }
          });

          // Draw tile background fill if hovered or rippled
          if (isHovered || rippleIntensity > 0) {
            ctx.fillStyle = rippleIntensity > 0
              ? `rgba(0, 112, 243, ${0.18 * rippleIntensity * cellAlpha})`
              : `rgba(23, 23, 23, ${Math.max(0.01, 0.09 * (1 - distMouse / (cellSize * 1.5)) * cellAlpha)})`;
            ctx.fillRect(x + 1, y + 1, cellSize - 1, cellSize - 1);
          }

          // Draw grid border lines with smooth falloff
          ctx.strokeStyle = rippleIntensity > 0
            ? `rgba(0, 112, 243, ${0.45 * rippleIntensity * cellAlpha})`
            : `rgba(23, 23, 23, ${0.08 * cellAlpha})`;
          ctx.lineWidth = 1;
          ctx.strokeRect(x, y, cellSize, cellSize);
        }
      }

      // Draw expanding stroke rings for click ripples
      ripplesRef.current.forEach((rip) => {
        ctx.beginPath();
        ctx.arc(rip.x, rip.y, rip.radius, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(0, 112, 243, ${0.35 * rip.opacity})`;
        ctx.lineWidth = 2;
        ctx.stroke();
      });

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      resizeObserver.disconnect();
      window.removeEventListener("resize", resize);
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("click", handleClick);
      cancelAnimationFrame(animationFrameId);
    };
  }, []);

  return (
    <div
      ref={containerRef}
      style={{
        position: "absolute",
        top: 0,
        left: "50%",
        transform: "translateX(-50%)",
        width: "100vw",
        height: "100%",
        zIndex: 0,
        pointerEvents: "none",
        overflow: "hidden",
      }}
    >
      <canvas
        ref={canvasRef}
        style={{
          display: "block",
          width: "100%",
          height: "100%",
        }}
      />
    </div>
  );
}
