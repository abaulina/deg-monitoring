namespace CryptographyLib.Helpers.OpenSslApi
{
    public class OpenSslApiProvider
    {
        private PlatformID _pid;
        public OpenSslApiProvider()
        {
            _pid = Environment.OSVersion.Platform;
        }

        public IntPtr BN_CTX_new()
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return OpenSslApiWindows.BN_CTX_new();
                case PlatformID.Unix:
                    return OpenSslApiUnix.BN_CTX_new();
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public void BN_CTX_free(IntPtr c)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    OpenSslApiWindows.BN_CTX_free(c);
                    return;
                case PlatformID.Unix:
                    OpenSslApiUnix.BN_CTX_free(c);
                    return;
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public IntPtr EC_POINT_new(IntPtr group)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return OpenSslApiWindows.EC_POINT_new(group);
                case PlatformID.Unix:
                    return OpenSslApiUnix.EC_POINT_new(group);
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public IntPtr BN_new()
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return OpenSslApiWindows.BN_new();
                case PlatformID.Unix:
                    return OpenSslApiUnix.BN_new();
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public void BN_free(IntPtr a)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    OpenSslApiWindows.BN_free(a);
                    return;
                case PlatformID.Unix:
                    OpenSslApiUnix.BN_free(a);
                    return;
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public int EC_POINT_add(IntPtr group, IntPtr r, IntPtr a, IntPtr b, IntPtr ctx)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return OpenSslApiWindows.EC_POINT_add(group, r, a, b, ctx);
                case PlatformID.Unix:
                    return OpenSslApiUnix.EC_POINT_add(group, r, a, b, ctx);
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public void EC_POINT_free(IntPtr point)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    OpenSslApiWindows.EC_POINT_free(point);
                    return;
                case PlatformID.Unix:
                    OpenSslApiUnix.EC_POINT_free(point);
                    return;
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public void EC_GROUP_free(IntPtr group)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    OpenSslApiWindows.EC_GROUP_free(group);
                    return;
                case PlatformID.Unix:
                    OpenSslApiUnix.EC_GROUP_free(group);
                    return;
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public IntPtr BN_bin2bn(byte[] s, int len, IntPtr ret)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return OpenSslApiWindows.BN_bin2bn(s, len, ret);
                case PlatformID.Unix:
                    return OpenSslApiUnix.BN_bin2bn(s, len, ret);
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public IntPtr EC_GROUP_new_curve_GFp(IntPtr p, IntPtr a, IntPtr b, IntPtr ctx)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return OpenSslApiWindows.EC_GROUP_new_curve_GFp(p, a, b, ctx);
                case PlatformID.Unix:
                    return OpenSslApiUnix.EC_GROUP_new_curve_GFp(p, a, b, ctx);
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public int EC_POINT_set_affine_coordinates_GFp(IntPtr group, IntPtr p, IntPtr x, IntPtr y, IntPtr ctx)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return OpenSslApiWindows.EC_POINT_set_affine_coordinates_GFp(group, p, x, y, ctx);
                case PlatformID.Unix:
                    return OpenSslApiUnix.EC_POINT_set_affine_coordinates_GFp(group, p, x, y, ctx);
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public int EC_GROUP_set_generator(IntPtr group, IntPtr generator, IntPtr order, IntPtr cofactor)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return OpenSslApiWindows.EC_GROUP_set_generator(group, generator, order, cofactor);
                case PlatformID.Unix:
                    return OpenSslApiUnix.EC_GROUP_set_generator(group, generator, order, cofactor);
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public int EC_POINT_set_compressed_coordinates_GFp(
            IntPtr group,
            IntPtr p,
            IntPtr x,
            int y_bit,
            IntPtr ctx)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return OpenSslApiWindows.EC_POINT_set_compressed_coordinates_GFp(
                         group,
                         p,
                         x,
                         y_bit,
                         ctx);
                case PlatformID.Unix:
                    return OpenSslApiUnix.EC_POINT_set_compressed_coordinates_GFp(
                         group,
                         p,
                         x,
                         y_bit,
                         ctx);
                default:
                    throw new PlatformNotSupportedException();
            }
        }


        public int EC_POINT_is_on_curve(IntPtr group, IntPtr point, IntPtr ctx)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return OpenSslApiWindows.EC_POINT_is_on_curve(group, point, ctx);
                case PlatformID.Unix:
                    return OpenSslApiUnix.EC_POINT_is_on_curve(group, point, ctx);
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public int EC_POINT_get_affine_coordinates_GFp(IntPtr group, IntPtr p, IntPtr x, IntPtr y, IntPtr ctx)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return OpenSslApiWindows.EC_POINT_get_affine_coordinates_GFp(group, p, x, y, ctx);
                case PlatformID.Unix:
                    return OpenSslApiUnix.EC_POINT_get_affine_coordinates_GFp(group, p, x, y, ctx);
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public int BN_bn2bin(IntPtr a, byte[] to)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return OpenSslApiWindows.BN_bn2bin(a, to);
                case PlatformID.Unix:
                    return OpenSslApiUnix.BN_bn2bin(a, to);
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public bool BN_is_odd(IntPtr bn)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return OpenSslApiWindows.BN_is_odd(bn);
                case PlatformID.Unix:
                    return OpenSslApiUnix.BN_is_odd(bn);
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public int EC_GROUP_get_order(IntPtr group, IntPtr order, IntPtr ctx)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return OpenSslApiWindows.EC_GROUP_get_order(group, order, ctx);
                case PlatformID.Unix:
                    return OpenSslApiUnix.EC_GROUP_get_order(group, order, ctx);
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public int EC_POINT_mul(IntPtr group, IntPtr r, IntPtr n, IntPtr q, IntPtr m, IntPtr ctx)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return OpenSslApiWindows.EC_POINT_mul(group, r, n, q, m, ctx);
                case PlatformID.Unix:
                    return OpenSslApiUnix.EC_POINT_mul(group, r, n, q, m, ctx);
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public int EC_POINT_cmp(IntPtr group, IntPtr a, IntPtr b, IntPtr ctx)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return OpenSslApiWindows.EC_POINT_cmp(group, a, b, ctx);
                case PlatformID.Unix:
                    return OpenSslApiUnix.EC_POINT_cmp(group, a, b, ctx);
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public int EC_POINT_invert(IntPtr group, IntPtr a, IntPtr ctx)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return OpenSslApiWindows.EC_POINT_invert(group, a, ctx);
                case PlatformID.Unix:
                    return OpenSslApiUnix.EC_POINT_invert(group, a, ctx);
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public int EC_POINT_copy(IntPtr dst, IntPtr src)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return OpenSslApiWindows.EC_POINT_copy(dst, src);
                case PlatformID.Unix:
                    return OpenSslApiUnix.EC_POINT_copy(dst, src);
                default:
                    throw new PlatformNotSupportedException();
            }
        }

    }
}
